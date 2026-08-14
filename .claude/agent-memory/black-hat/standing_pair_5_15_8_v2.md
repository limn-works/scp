---
name: standing-pair-5-15-8-v2
description: Adversarial findings against §5.15.8 standing-pair creation (single-context async). v2 had 6 findings @37cf92e51; ALL CLOSED @bfd82ee47 (final confirming pass).
metadata:
  type: project
---

# §5.15.8 Standing-Pair adversarial review — branch spec/standing-pair-not-a-saga-v2

Classification SETTLED (single-context async, not a saga). Attack the SECURITY CLAIMS.

## Final confirming pass @ bfd82ee47 — VERDICT: CLEAN
All 6 prior findings (from @37cf92e51, below) are CLOSED at bfd82ee47 by disclosed-inherent-residual handling, not false closure. No undisclosed-bypass / false-closure / new-vector. One MINOR doc-locality nit only.

How each prior finding closed at bfd82ee47:
- **SP-01 (consent self-clear)** → CLOSED. Per-arm TrustRequirement treatment (step 4(b)). `shared_context`: not-self-created-by-EITHER-party + distinct (distinct ≠ "any other context"). `discovery_context`: SYMMETRIC not-self-created-by-either (closes the asymmetric self-clear a single-predicate fix misses — the non-obvious one). `known_did`: no manufacture surface; residual = B's allowlist hygiene. Confederate residual = inherent semantics, disclosed.
- **SP-02 (SDK-policy not protocol-enforced)** → CLOSED-as-disclosed. New *Enforcement layer (honest disclosure)*: normative MUST at SDK consent-gate; explicitly does NOT imply protocol enforcement; non-overridable intent (SDK MUST NOT let AutoAcceptPolicy override stranger-deny), same class as §5.12.2 tool/paid hard rules.
- **SP-03 (adversary-triggerable destroy)** → CLOSED + disclosed. Creator-credential CRYPTOGRAPHICALLY BOUND check (ScpCredential.did==did_lo AND leaf sig key resolves to did_lo DID-VM per §9.7.1) forecloses forged-creator-string DoS. did_lo-insider unilateral race-win disclosed under *Known limitation→Security-relevant*: bounded to receive-but-not-send in that one pair until Phase-2E, no cross-pair/key effect.
- **SP-04 (published-KeyPackage oracle)** → DISCLOSED + chain-break. *Scope of claim*: KP-existence bit is a targeting primitive ONLY when chained w/ stranger-bar bypass; not-self-created/distinct qualifier is the named control blunting the chain.
- **SP-05 (destroy timing signal)** → marginal, subsumed.
- **SP-06 (fresh-DID fleet)** → CLOSED-as-disclosed. Per-DID cooldown governs APPROVAL-PROMPT-rate, not join flood. Fleet = approval-prompt-spam DoS NOT unauthorized-join (default-deny ⇒ N prompts never N silent joins). Bounded by §9.3 minting cost. Spec honestly states §9.3 defines NO recipient-side inbound tier check, so claims none.

NEW edit attacked (binding-enrichment prohibition) → CLOSED, no binding-layer residual:
- "FFI/SDK bindings MUST NOT enrich standing_context return w/ create-vs-found OR peer-join discriminant." Names BOTH discriminant classes (closes the patch-one-leak-the-other gap). Reinforced by register_standing_context being NEVER an FFI export (only standing_context get-or-create exported) ⇒ no 2nd bridge path.
- Residual check: found-vs-create LATENCY hint (§5.12.5 ~0ms/~200ms) permitted ONLY for verified-member's-own-pair success path. Binding prohibition = VALUE channel; non-member path constant-time-wrt-existence (separate AlreadyExists clause). Compose w/o oracle to any unauthorized party — only the pair member sees its own-pair latency, which it's entitled to.
- MINOR (doc locality only, NOT a gap): a binding author reading only the Ok-return contract could under-implement the constant-time non-member timing requirement (it lives 2 paras down in AlreadyExists clause). One cross-pointer sentence would help. Normative MUST already present.

Other CLOSED claims verified @bfd82ee47:
- Collision-destroy replay: *Welcome-freshness binding* gates destroy on LIVE join (init key unconsumed at fused-join two-anchor, ADR-049 §9). Replayed/stale did_lo Welcome fails join ⇒ no destroy. Gated on SAME primitive as join (no divergeable separate anchor) — strong.
- Confused-deputy via context-recreate: {confirm-creator + fresh-join(consume init key) + destroy} ATOMIC under per-context actor mutex + generation/identity check. Names mutex+gen, not just "atomically." Closes the deterministic-id confused-deputy class.
- AlreadyExists oracle: value+timing indistinguishable; new *Implementer mechanism* (resolve-membership-first / fixed-cost path, branch on membership never existence) makes the MUST mechanically achievable.
- Injectivity provenance correction: RETRACTS prior wrong "backstop removed/sole anchor now" → "colon-join was ALWAYS sole anchor; saga group_id was saga's MLS id, never isolation co-anchor." Accuracy improvement, not weakening. MLS DiD (GroupId+key schedule+creds) independent.
- Reaper deliverability predicate: A-LOCAL observation-free (max over A's own per-relay emit timestamps) — no relay/peer probe reintroduces a signal.

## Original v2 pass @ 37cf92e51 (superseded by bfd82ee47 hardening — kept for lineage)
SP-01 HIGH consent self-clear (single-predicate "no prior shared context"); SP-02 MED SDK-policy not protocol-pinned; SP-03 MED adversary-triggerable destroy; SP-04 LOW/MED published-KeyPackage oracle; SP-05 LOW destroy timing; SP-06 MED fresh-DID fleet. All now closed/disclosed above.
