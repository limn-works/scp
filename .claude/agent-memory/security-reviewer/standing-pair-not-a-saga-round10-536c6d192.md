# Standing-Pair "Not a Saga" §5.15.8 Round-10 (536c6d192) — 2026-06-24 — ZERO FINDINGS / SOUND

Branch spec/standing-pair-not-a-saga-v2. HEAD=536c6d192. Docs-only.
Prior reviewed HEAD = fd3b2fd2a (round-9, zero findings). 536c6d192 is the ONLY commit on top.
Touches just **2 files**: 03-identity.md (§3.8.1) + 05-contexts.md (§5.12.2 + §5.15.8 step-4a0/anti-spam/self-heal).
Other merge-base-diff files (ADR-049/DEFERRED/sketch.md/sdk-common.md/09-security-model.md) = EARLIER rounds, unchanged here.
NO mechanism change — precision/honesty/disclosure only. Commit self-states "9/11 reviewers cleared fd3b2fd2a."

## 8 fixes, all STRONGER or honesty-improving (verified):
1. **FIX-1 mismatch-guard narrowed (ACCURATE).** step-4(a0) no longer claims to "restore the cross-party
   agreement check." VERIFIED against §5.12.3.1 (05-contexts.md L798-824): InvitationBundle.context_id is a
   `String`, creator-signed as `SHA-256("SCP-INVITATION-BUNDLE-V1:"||context_id||creator_did||...)` — bound to
   creator_did ONLY, NOT to the DID pair. So a malicious A CAN label the bundle with the id B derives ⇒ guard
   catches HONEST canonicalization divergence (did:web) only, not adversarial split-brain. Agreement vs dishonest
   creator rests on §9.7.1 bound-creator + MLS membership. Framing now precise, not over-claiming.
2. **FIX-1 did:web availability dual (ACCURATE).** Same guard turns adversarial did:web divergence into
   undiagnosable pairing-denial (no-oracle vs diagnosability tension). Accepted explicitly; bounded (did:web
   fallback-only §3.8/§9.6.2; did:dht airtight, unaffected).
3. **FIX-2 non-mismatch failure-states + atomic-sequence fold (SOUND).** transient resolve fail = retryable
   deferral within welcome_ttl (7-day relay-retention, consistent w/ reaper item(d) + convergence window L1852);
   permanent un-canonicalizable = reject; never silent join. id-agreement folded as FIRST gate
   {id-agreement → block-list → confirm-bound-creator → fresh-join → destroy}. Reconciles a0-mismatch/ignore +
   consent-reject as ONE ordered path (not competing gates); did_lo-ignore framed as "(a0)-LEVEL" decision
   (pre-consent stage; slight stretch since a0=equality vs did_lo-ignore=already-hold-own-group, but spec says
   "level" not the literal test — consistent). No new oracle/DoS; deferral = no synchronous reply.
4. **FIX-3 three-arm first-contact coverage AIRTIGHT.** §5.12.2 L755-758 + step-4(b) cross-ref now name all 3
   TrustRequirement arms (defs L743-746): shared_context (not-self-created by EITHER party + distinct);
   discovery_context (not-self-created/admin'd BY CANDIDATE — closes self-register-into-own-discovery-ctx
   self-clear → silent memory_scope:full pair); known_did (evaluator allowlist, self-clear-resistant by
   construction). The shared(either-party) vs discovery(candidate-only) ASYMMETRY is JUSTIFIED: discovery trust
   is evaluator-anchored (operator deliberately trusts the discovery ctx), shared trust is mutual-membership.
   Evaluator trusting an open-registration discovery ctx they configured = operator choice, not protocol gap.
   No residual self-clear / unsolicited-auto-join path.
5. **FIX-4 drop-filter downgraded to PRECISE TRUTH (strict honesty improvement, NOT weakening).** Now: SHOULD
   suppresses APPLICATION-SURFACING only; did_hi stays live MLS member, MUST still process did_lo inbound for
   ratchet sync ⇒ resource+ratchet+presence residual until Phase-2E; SHOULD has NO enforcement (non-conformant
   SDK skips). VERIFIED: §3.7.1 L537 severance = "rotate sender key" (a SEND) ⇒ send-gated did_hi can't sever;
   §9.16.7 L1387 = BLOCKED party purges BLOCKER's content (directional) ⇒ does NOT cover BLOCKER dropping
   BLOCKED party's inbound ⇒ drop-filter fills a genuine gap, accurate. Prior r9 wording said "reaches no app
   surface" w/o disclosing ratchet/presence residual; FIX-4 discloses it. More honest.
6. **FIX-5 anti-spam CPU-DoS amplifier (HONEST + complete).** Now discloses: convergence-candidate exemption
   precondition (victim holds own self-created group under id) is met for EVERY pair victim ever initiated, and
   derived_context_id is PUBLICLY computable ⇒ ANY party knowing both DIDs can forge convergence Welcomes forcing
   un-throttled 1 DID-resolve + 1 sig-verify each. Bounded: no amplification (no join/state/fan-out). Correctly
   retracts the prior implication that the precondition is hard to reach.
7. **FIX-6/7 (CONSISTENT).** §3.8.1 percent-encoding hex-case vs host/scheme alpha-case = orthogonal disjoint
   normalizations (RFC 3986 §6.2.2.1 — factually correct: hex digits inside %XX vs literal ALPHA, different
   chars). "retires method-admission gate" → "retires colon-freedom method-admission DEPENDENCE"; §3.8.1 L766
   RETAINS the fail-loud agreement gate; §5.15.8 injectivity-invariant L145 now agrees. No internal contradiction.
8. **FIX-8 MLS defense-in-depth compressed** to ~1 sentence + RFC 9420 cross-ref. Substance unchanged.

## Load-bearing guarantees CONFIRMED INTACT (not regressed):
- Existence/decline oracle closure (Ok-return contract, value+timing) — unchanged context, intact.
- FFI no-enrich clause (no created:bool / peer_joined discriminant; identical shape all bindings) — intact.
- Consent/block-list-FIRST gate + confirm-bound-creator + fresh-join(init-key single-use) + destroy under
  actor mutex + generation check — unchanged; confused-deputy/replay/forged-creator still caught.
- KeyPackage drain = general MLS pool concern, bounded by republication + §9.3 — intact.
- Length-prefix injectivity (§9.5.1) unconditional by construction — intact.

## Provenance — ALL grounded (no phantom): §5.12.3.1 L793-824, §9.7.1 L587 (KeyPackage-sig/DID-VM),
§9.3 L227 (not-self-created), §3.8.1 L753-766, §9.16.3 L1333, §9.16.7 L1385-1397, §3.7.1 L534-558,
ADR-049 §Follow-ups #1 L392/396, welcome_ttl (7-day) L1852/1858/1870, RFC 3986 §6.2.2.1, RFC 9420.

## OBSERVATION (carried fwd, impl program not a finding): drop-filter SHOULD still has no named enforcement;
Phase-2E wiring PR needs a pipeline_wiring.rs-class assertion for blocker-side inbound drop. FIX-4 now states
the no-enforcement reality explicitly in-spec, which is the honest interim stance.

## GOTCHA: prior round memory files (round8 a0e02ab3b) live in MAIN worktree, not this worktree path.
