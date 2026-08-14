---
name: spec-5-15-8-standing-pair
description: Adversarial review of §5.15.8 standing-pair creation (single-context async, not a saga) — all security claims hold as of commit 4dab1f296
metadata:
  type: project
---

# §5.15.8 Standing-Pair Creation — adversarial confirming pass (branch spec/standing-pair-not-a-saga-v2 @ 4dab1f296)

**Classification SETTLED**: standing pair = ONE MLS context, two members; MLS + event-log consistency layer; no cross-context atomicity; NOT a saga; journals nothing. (Was wrongly a 2PC saga in PR #1793; corrected 2026-06-18.)

**Verdict (2026-06-24): all security claims HOLD. Zero UNDISCLOSED-BYPASS / FALSE-CLOSURE / NEW-VECTOR.** Every residual correctly labeled DISCLOSED-INHERENT-RESIDUAL.

## Closed vectors (do not re-flag as findings)
- **Consent self-clear, all 3 arms** — shared_context (not-self-created-by-EITHER-party + distinct); discovery_context (SYMMETRIC guard — either party self-create blocked, the strongest fix in the edit); known_did (no manufacture surface, trust asserted by B directly). Per-arm decomposition is correct; uniform predicate would be the false closure.
- **Collision-destroy (did_hi destroys own group)** — forge CLOSED (cryptographic DID-VM bound creator check per §9.7.1, not self-asserted string); replay/stale-destroy CLOSED (destroy gated on LIVE-join unconsumed init-key, same single-use as join, ADR-049 §9); confused-deputy CLOSED (per-context actor mutex + generation check held across confirm+join+destroy); orphan CLOSED (destroy strictly AFTER join succeeds). did_lo ignores did_hi Welcome → destroy equivocates against no peer. Convergence window = eventual not synchronous one-group guarantee.
- **Existence oracle** — non-member AlreadyExists returns generic rejection, constant-time WRT existence (value AND timing both closed; latency-branch forbidden; §5.12.5 found-vs-create hint scoped to verified-member success path only).
- **Block oracle** — consent-on-receipt, no synchronous Rejected. Honestly scoped: only the SYNCHRONOUS oracle closed; published-KeyPackage-existence bit is relay-observable (disclosed), becomes targeting primitive only chained with stranger-bar bypass.
- **KeyPackage drain** — no standing-pair-local reservation; single-use enforced at join (fused-join two-anchor); drain = general MLS pool concern.

## Disclosed-inherent residuals (acceptable, by-design — NOT findings)
- Confederate third-party vouching (shared_context inherent semantics)
- Malicious/compromised curator (discovery_context inherent delegation)
- Stale known_did entry (B's own allowlist hygiene)
- Fresh-DID-fleet = approval-PROMPT-spam DoS, NOT unauthorized-join flood (default-deny gate means N prompts max, never N joins; bounded by §9.3 per-DID minting cost; spec invents no recipient-side tier check §9.3 doesn't define)
- Injectivity: colon-join is SOLE structural isolation anchor for derived_context_id (no group_id backstop ever — the saga-cut group_id was the saga's MLS group id, not co-anchor). Safe for ALL admitted methods (did:dht z-base-32, did:web %3A-encoded). Rides on human method-admission gate. Length-prefix framing (§9.5.1) = RECOMMENDED follow-up (unconditional injectivity, retires human gate), deferred because derived_context_id derivation change needs byte-identical both-party coordination. MLS-layer defense-in-depth: even on collision, GroupId+key-schedule+credentials independent → collision grants NO plaintext, only create-time DoS.

## Cross-refs verified faithful (no drift)
- §9.3 (09-security-model.md:227) literally "participation records from distinct contexts (not self-created)" — imported exactly
- §3.7.1 (03-identity.md:545) is_globally_blocked(blocker,target) = B's own private state; step 4(a) = is_globally_blocked(B,A). Correct.
- §5.12.2 (05-contexts.md:752) agrees on not-self-created qualifier for first-contact shared_context
- §9.7.1 DID-VM binding = correct anchor for cryptographic creator check
- Entry::Vacant guard keys on SHA-256("standing-" ‖ hex(derived_context_id)), 1:1 collision-resistant fn of derived_context_id — isolation chain holds end-to-end

## Threat-model carry-forward
- Length-prefix framing is the ONE residual with no mechanical backstop (human gate + MLS DiD only). Until it lands, "new DID method admission MUST verify method-specific-id colon-freedom" is a gating checklist item.
- Published-KeyPackage-existence bit is a permanent unclosable metadata leak; control is the stranger-bar qualifier, not the reply channel.
