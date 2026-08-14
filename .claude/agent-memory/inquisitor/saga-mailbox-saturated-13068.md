---
name: saga-mailbox-saturated-13068
description: SCP-SAGA-13068 Prepare ActorBusy → retryable abort. CONVERGED & SOUND at HEAD a32f3a723 (renamed MailboxSaturated→ParticipantUnavailable). Two residual soft QUESTIONs only.
metadata:
  type: project
---

# §6.2.4 saga: Prepare ActorBusy → ParticipantUnavailable (SCP-SAGA-13068)

## FINAL PASS @ a32f3a723 — VERDICT: SOUND, CONVERGED.
The variant was RENAMED `MailboxSaturated` → `ParticipantUnavailable`. This directly
fixed my prior central concern (the old name foregrounded the LEAST-reliably-reached
subcase). The new name generalizes honestly across all 3 handle.rs `send` producers
(reply-dropped / inbox-closed / mailbox-full) — a participant that won't reply IS
"unavailable" from the saga's view. Verified:
- Spec §6.2.4 + ADR §3a now HONEST about saturated-vs-closed: closed/terminated is
  reliably reached; transiently-full-but-OPEN "may instead surface as a generic
  Prepare-timeout abort" while `SEND_TIMEOUT(30s) == PHASE_TIMEOUT(30s)` (still equal,
  handle.rs:46 / supervisor.rs:6632,6809). Spec is no longer ahead of reality.
- Fieldless UNIT variant — no dead `retry_after_ms`. FFI folds
  `ParticipantUnavailable | Rejected => None` (saga_errors.rs).
- Lift ordering CORRECT + test-pinned: `needs_repair` short-circuits BEFORE the
  `ActorBusy` arm, so a COMMIT-phase ActorBusy → `NeedsRepair` (divergence-safe), only
  Prepare-phase → retryable abort. Test `lift_..._actor_busy_with_needs_repair_is_
  needs_repair_not_aborted` pins it. Lift is at the right layer (single saga-error home).
- Prepare-B uses `actor.send(...)` (supervisor.rs:6733) → all 3 ActorBusy producers
  reachable incl. reply-dropped; "neither committed" holds via normative RAII
  release-or-reconcile clause (validated prior pass).
- All 4 SDK bindings now honestly say Aborted may be permanent OR retryable,
  "distinguished by the SCP-SAGA-* code" — no over-claim.

### Two residual SOFT QUESTIONs (neither blocks; not UNSOUND):
1. Variant rustdoc self-declares "SINGLE authoritative home" but enumerates only
   inbox-closed / terminated / saturated — OMITS the reply-dropped-after-delivery
   producer (handle.rs:131) that its OWN test names. Framing "unavailable to ACCEPT
   the send / immediate ActorBusy on send" is inaccurate for reply-dropped (send WAS
   accepted; ActorBusy arises post-processing from a dropped reply on handler-panic /
   actor-shutdown). The test is more honest than the authoritative doc. Fix: list the
   reply-dropped producer in the variant rustdoc + soften the "on-send" framing.
2. CARRIED: FFI fold flattens `ParticipantUnavailable | RateLimited(None) | Rejected`
   into `Aborted{None}`; retryability discernible only by numeric `code` — no
   structural `retryable` flag / reason enum across the FFI. Pre-existing class
   (RateLimited-None already shared it), EXTENDED not introduced here. Against
   agent-first "enums over booleans." Deferral legit ONLY IF a follow-up targets the
   ROOT (carry the reason enum or a `retryable` bool on the FFI Aborted kind), not just
   this variant — could not verify the follow-up exists from committed code.

# (prior passes, for provenance)
# §6.2.4 saga: ActorBusy → MailboxSaturated{retry_after_ms} (SCP-SAGA-13068)

Branch `fix/121-mailbox-saturated-saga-terminal`. Maps a Prepare-phase
`ContextError::ActorBusy` to a NEW retryable `SagaAbortReason::MailboxSaturated`
under the existing `SagaError::Aborted` terminal (FFI folds into `Aborted{retry_after_ms}`).

**Verdict: SOUND.** The decision is unusually well-grounded:
- Upstream artifact (spec §6.2.4 amendment, commit 4cfb643c6) explicitly defines this
  as a "retryable **clean abort** — neither side committed, same all-or-nothing as a
  Prepare timeout." Not invented in code.
- "neither committed" is backed by the normative RAII reservation-release clause
  (Prepare-B's tool-session reservation MUST release on every terminal incl. operation
  panic / supervisor cancellation). RAII discipline is real: `ToolEconomyTicket: Drop`
  (tools_helpers.rs:170), `send_recover_on_failure` (handle.rs:146) exists specifically
  to reverse must-use tickets on send failure.
- "retryable" is backed by real machinery: backpressure drain (full case), actor
  respawn budget + poison backstop (closed case, ADR-049 §10).
- Rejecting `SagaError::Busy` (alt a) is spec-reasoned: mailbox saturation ≠
  participant-context-set overlap; `contended_context` wouldn't apply.
- Folding into `Aborted{retry_after_ms}` with RateLimited is fine — code `13068`
  disambiguates; both genuinely reduce to "back off and retry."

**UPDATE @ HEAD afc795ef2 — both prior findings RESOLVED:**
- The "never delivered" over-claim is GONE. Variant doc + lift doc now ground on
  "NEITHER side committed (reservation released **or reconciled** on every terminal
  path)" — true for all 3 producers incl. reply-dropped-after-delivery. "reconciled"
  is the honest hedge the old wording lacked.
- The always-None `retry_after_ms` FIELD was removed; variant is now a fieldless UNIT.
  FFI folds `MailboxSaturated | Rejected => None`. No dead surface remains.

**NEW finding (spec↔code coherence, QUESTION not UNSOUND):** Spec §6.2.4 promises
"mailbox **saturated OR closed** → retryable abort." But code reliably maps only the
CLOSED subcase. `SEND_TIMEOUT`(handle.rs:46)=30s == `PHASE_TIMEOUT`(supervisor.rs:7058,
7267)=30s — equal timers. A full-but-OPEN mailbox is a literal race; may surface as
generic 13067/`Rejected` (appears permanent). Code doc HONESTLY discloses this
("may instead race the phase timeout"); the SPEC sentence is the artifact now ahead of
reality. Pointed: variant NAMED `MailboxSaturated` foregrounds the LEAST-reliably-reached
subcase. Fix per one-way flow: soften spec (closed→retryable; full may→generic timeout)
OR set SEND_TIMEOUT < PHASE_TIMEOUT. Functionally safe (13067 is also no-commit).

**Carried QUESTION:** FFI retryability signal lives ONLY in code string `13068` —
`MailboxSaturated` is kind-indistinguishable from permanent `Rejected` (both
`Aborted{None}`). Pre-existing class (token-bucket RateLimited shares it). Deferral to
follow-up legit IFF the follow-up names the ROOT (first-class `retryable` flag on the
FFI Aborted kind), not just this variant. Against agent-first "enums over booleans."

**Original (pre-refinement) finding, for provenance:** `ActorBusy(String)` is ONE
variant produced by THREE conditions in handle.rs:131-143 — full + closed (never
delivered) + reply-dropped-AFTER-enqueue (DELIVERED). Old doc-comments asserted "never
delivered," FALSE for the reply-dropped subcase. Now fixed (see UPDATE above).

Root cause of the comment hazard: `ContextError::ActorBusy(String)` conflates
delivered-vs-never-delivered — info the handle layer KNOWS (the three match arms) but
discards into an opaque String. Mirrors the project's own "carry codes STRUCTURALLY,
never parse the message" principle, NOT yet applied to ActorBusy's own sub-conditions.
