---
name: adr049-s15-crypto-move-premise
description: Premise verdict on ADR-049 §15 (PR-7 crypto-state move is one atomic PR) and its respawn-invariant prose gap
metadata:
  type: project
---

ADR-049 §15 ("PR-7 crypto-state move is one atomic PR, not per-domain") interrogated 2026-07
before it landed as immutable ADR provenance (worktree `adr049-pr7-docs`).

**Verdict: decision SOUND, atomic premise FORCED, one prose/mechanism contradiction to reconcile.**

- **Atomic-move premise holds.** `take_crypto_state` (`crypto/mls/provider.rs:655`) is atomic/one-way:
  `DashMap::remove` from `contexts` + insert into `taken_context_ids`; afterward every `deps.crypto.*`
  on that ctx returns `CryptoFailed("context state owned by actor")`. Combined with §1 (actor-owns-by-move,
  single authoritative home) and the rejected dual-home, a per-domain slice is impossible without either
  a broken build or reintroducing dual-home (the exact anti-pattern PR-6 just removed for floors). The
  "take in last PR" middle path collapses into dual-home. So one atomic PR is forced, not preference.
  32 sites confirmed by grep: lifecycle 16 / messaging 5 / governance 4 / ttl_close 3 / trust_recovery 3
  / broadcast 1.
- **Ownership-not-creation boundary is clean + stable.** Provider stays birth/restore seam
  (`create_mls_group`/`add_member` survive); 100% of steady-state reads move to actor. Deferring
  actor-births-directly to §6 dissolution DECOMPOSES the follow-on (§6 only moves birth + deletes provider),
  it does not compound it. Mechanically checkable via the zero-grep AC.

- **THE reconciliation point (was open at review time):** §15's "Respawn preserves the one-way take
  invariant" says restore "reconstitutes ... directly ... into the new actor" and "does NOT round-trip a
  taken context back through the provider's contexts map" — but in the SAME paragraph names the mechanism
  "mint-or-**install**-then-move." Current `restore_crypto_state` (provider.rs:2643) does
  `self.contexts.insert(...)` — it DOES transit the provider contexts map. The two phrasings contradict.
  The TRUE load-bearing invariant is narrower: *no STEADY-STATE per-context crypto read touches the
  provider after take*; the transient install-then-take at the respawn seam is single-threaded, pre-command,
  leaves nothing for steady-state. `taken_context_ids` is never cleared (restore doesn't touch it; take
  re-inserts idempotently) — that sub-claim holds. The PRD action item ("reconstitute ... not via the
  provider contexts map") had already inherited the overclaim. Fix = pick ONE: (Option B, cleaner) have a
  restore variant return `OwnedMlsCryptoState` directly instead of insert+take, then the literal claim is
  true; or (Option A) keep install-then-take and replace "never round-trips the contexts map" with the
  steady-state phrasing + state the take-immediately-follows-install ordering obligation.

Everything else (§9 Class-S sender_key_epoch treatment, floors-stay-in-registry, single-story scope
exception vs prd.md §granularity) checked SOUND. The prd.md ~3-file/~30-min rule is soft guidance whose
remedy ("split with a blocking sequence") is inapplicable to indivisible work; a recorded scope exception
is the honest model and fabricating sub-stories would be phantom provenance.

**UPDATE 2026-07 (post-Prep A–E merge, origin/main c34387059+, re-interrogated the PR-7 draft plan):**
- **Prior open reconciliation RESOLVED in the landed ADR.** §15 now reads "restore RETURNS the owned
  crypto material (an `OwnedMlsCryptoState`) together with `RestoredFloors`, WITHOUT inserting into
  `provider.contexts` and WITHOUT calling `take_crypto_state`" and states the once-taken-never-returns
  invariant "holds LITERALLY across warm respawns and cold restarts." The install-then-take overclaim I
  flagged is gone. Verified take_crypto_state atomicity still holds (provider.rs:704, remove-then-insert
  one-way). MlsCryptoSnapshot stays pub(crate) — 2 refs in actor state.rs (import :96, use :2396,
  actor export_crypto_state). Seam inventory (~30 relocating sites) verified accurate & nuanced
  (flip / exempt local_did / removed destroy_* / re-plumbed sig), not naive.
- **THE SEAL FORK is where the plan is shaky.** `recovery_send_notification_direct` (supervisor.rs:3950)
  seals a no-live-actor context via the shared provider. Plan's option set (a transient-materialize /
  b retained-provider recovery_seal / c hybrid) is INCOMPLETE — it misses option (d): route real-member
  recovery seals through the NORMAL actor path via lazy-spawn (the ADR comment itself names "ADR-049
  lazy-spawn"; the registered-actor handler `recovery_send_notification` already exists). The
  "seal-without-an-actor" requirement is a PROVENANCE ARTIFACT of provider-centrism (supervisor could
  seal anything because the provider centrally owned all crypto); the actor model obviates it.
  Option (a) — which the planner RECOMMENDED — has a CONCRETE reachable nonce-reuse bug: revoke_ucans
  (seq1) + rotate_key_packages (seq2) seal the SAME real member context in one compromise recovery; two
  transient materializations from the same durable snapshot reuse (sender_key_epoch, send_sequence) →
  AES-GCM nonce reuse. Option (d) is nonce-safe by construction (respawned actor persists send_sequence
  before ack, Class-S). Synthetic identity-private-state seal is ALREADY a production no-op:
  seed_identity_private_state_group is #[cfg(test)] (identity/recovery.rs:1255), so no prod MLS group →
  provider.seal errors → rotate_psk returns false (best-effort). If PSK rotation is supposed to work in
  prod, that's a PRE-EXISTING bug, NOT PR-7 scope — do not smuggle its fix into the seal fork.
- **Artifact-flow flag:** §15's "materialize the state for the recovery seal rather than reaching a live
  actor" phrasing smuggles a false dichotomy that forecloses option (d) (spawn-if-absent → reach the
  now-live actor). If the team adopts (b) or (d), amend the ADR §15 sentence FIRST (it's an explicit
  open-impl-detail flag, so correcting it is legitimate) — the plan only mentions amending the zero-grep
  AC, which is downstream and insufficient.
