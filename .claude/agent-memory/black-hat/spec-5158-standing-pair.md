---
name: spec-5158-standing-pair
description: Adversarial confirming-pass result for §5.15.8 standing-pair creation security claims (spec/standing-pair-not-a-saga-v2 @ bfd82ee47)
metadata:
  type: project
---

# §5.15.8 Standing-Pair Creation — security claims hold (confirming pass, 2026-06-24)

Branch `spec/standing-pair-not-a-saga-v2` @ `bfd82ee47`. DOCS-ONLY. Classification (single-context async, not a saga) is SETTLED. Attacked the SECURITY CLAIMS. VERDICT: holds. Zero UNDISCLOSED-BYPASS / FALSE-CLOSURE / NEW-VECTOR. Three LOW observations, none blocking.

**Why:** Independent black-hat confirmation requested. Spec is unusually careful and self-correcting.
**How to apply:** Future passes on standing-pair / deterministic-id contexts can start from these confirmed-closed mechanisms rather than re-deriving.

## Confirmed CLOSED mechanisms (don't re-litigate without new evidence)
- **Collision-destroy replay**: destroy gated on SAME single-use init-key consumption that gates the join (ADR-049 §9 two-anchor). Replayed genuine did_lo Welcome passes crypto creator-check but FAILS join (init key consumed) → destroys nothing. Best part of the section.
- **Confused-deputy via context-recreate**: {confirm-creator + fused-join + destroy} atomic under per-context actor mutex + generation/identity check. Explicitly named. Matches deterministic-id mitigation requirement.
- **Forge-creator-string DoS**: cryptographically BOUND check — ScpCredential.did==did_lo AND MLS sig key == VM resolved from did_lo DID doc (§9.7.1). Self-asserted string insufficient.
- **Existence/AlreadyExists oracle**: closed at VALUE + TIMING (constant-time-wrt-existence, branch only on membership) + FFI-enrichment layer (prohibits created:bool / peer_joined:bool).
- **Per-arm TrustRequirement**: shared_context (not-self-created-by-either), discovery_context (SYMMETRIC guard), known_did (no manufacture surface, correctly predicate-free). NOT a blanket predicate — correct design.

## Confirmed DISCLOSED-INHERENT-RESIDUALS (acceptable, honestly framed)
- shared_context: third-party confederate transitive trust (inherent semantics)
- discovery_context: malicious curator vouching (inherent delegated trust)
- known_did: B's own allowlist hygiene
- Fresh-DID-fleet: approval-prompt-spam DoS NOT unauthorized-join (default-deny gate → N prompts never N silent joins); bounded by per-DID §9.3 minting cost. Spec correctly does NOT fabricate a recipient-side §9.3 tier check (§9.3 defines none).
- KeyPackage drain: general MLS pool concern, no standing-pair-local reservation invented.
- Injectivity: colon-join safe for admitted methods (self-delimiting fixed-alphabet method-specific ids: did:dht z-base-32, did:web %3A). Residual = human method-admission-review gate. Length-prefix framing (§9.5.1) = RECOMMENDED hardening follow-up, correctly deferred (coordinated spec+code change).
- Published-KeyPackage-existence bit relay-observable (step 2 fetch before gate) — disclosed; becomes targeting primitive only chained with stranger-bar bypass, which not-self-created qualifier blunts.

## Cross-refs verified ACCURATE against targets
§9.3 line 227 "(not self-created)" verbatim; §3.7.1 line 545 is_globally_blocked sig; §5.12.2 line 752 (co-edited to carry not-self-created/distinct qualifier); §5.12.5 line 951 ~0ms/~200ms hint.

## LOW observations (recorded, not findings)
- OBS-1: did_lo-relative attacker deterministically wins collision (DID order public) → pushes victim onto send-gated path until Phase-2E. Spec acknowledges; bounded single-pair, no key exposure, no cross-pair. Suggest a durable threat-model bullet.
- OBS-2: malicious relay can drop A's Welcome; A holds orphan single-member replica for TTL window. Benign local-retention, re-drive re-emits. Cannot force destroy.
- OBS-3: self-only-no-Welcome re-drive races collape into same actor-mutex+generation atomicity. OK.
