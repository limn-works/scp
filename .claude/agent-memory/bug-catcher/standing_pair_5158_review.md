---
name: standing-pair-5158-review
description: bug-catcher logical-defect sweep of spec §5.15.8 standing-pair-not-a-saga (branch spec/standing-pair-not-a-saga-v2 @4dab1f296)
metadata:
  type: project
---

# §5.15.8 Standing-Pair Creation (Single-Context Async) — logical-defect sweep

Branch `spec/standing-pair-not-a-saga-v2` @ `4dab1f296`. DOCS-ONLY. Reclassifies standing-pair from a 2PC cross-context saga to ordinary single-context async MLS creation (one MLS group, two members). Verified against ADR-049 (standalone file `.docs/adrs/ADR-049-actor-per-context.md` §3/§3a/§9 two-anchor single-use/§Follow-up #1 spawn-from-Welcome/§212 BLACK-002 auto-revive), §9.7.1 (KeyPackage-sig↔DID-VM binding), §9.3 (Sybil), §5.12.3.3 (InvitationBundle 7d relay TTL).

**Verdict: CLEAN on the core logic.** No CRITICAL/HIGH logical contradiction. The collision-resolution ordering {confirm-creator(bound) → fused-join(consumes init-key, fails on replay) → destroy} under per-context actor mutex + generation check is internally consistent and correctly forecloses: forged-creator-string DoS, captured-Welcome-replay stale-destroy, confused-deputy recreate-between-confirm-and-destroy. Send-gating claim (all Welcome-joiners DECRYPT-not-SEND until Phase-2E) exactly matches ADR-049 §Follow-up #1. Consent-on-receipt block-privacy oracle reasoning sound (honestly scopes to synchronous oracle only; discloses published-KeyPackage relay-observable bit). Existence-oracle constant-time clause is mechanically specified (membership-first, fixed-cost path). Get-or-create idempotency + self-only-no-Welcome re-drive distinction is coherent. Per-DID anti-spam floor (60s default, 1s hard floor) + honest fresh-DID-fleet residual disclosure correct.

**Provenance cross-check:** ADR-049 §3a explicitly pins standing-pair AlreadyExists is NOT a saga terminal and register_standing_context has no FFI export — spec matches. ADR-049 §212 BLACK-002 auto-revive matches §5.15.8's reaper/re-drive. §9.7.1 grounds the bound creator-credential check (ScpCredential.did==did_lo AND MLS sig key ∈ did_lo DID doc).

**Only LOW/NIT items found (see review output):** reaper "maximum over ALL relays welcome_emit_time" is A-local-observation-free but A cannot observe other relays' actual emit times — it uses its own emit timestamp per relay (benign, conservative); minor: "convergence window" benign-divergence prose could note the event-log consistency layer would flag two distinct self-created groups if both ever emitted checkpoints under same id (it doesn't, because did_lo ignores did_hi's group — non-issue). No fix required.
