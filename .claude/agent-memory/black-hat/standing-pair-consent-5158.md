---
name: standing-pair-consent-5158
description: Adversarial findings on §5.15.8 standing-pair consent surface (per-arm TrustRequirement qualifiers, fresh-DID fleet, collision-destroy)
metadata:
  type: project
---

# §5.15.8 Standing-Pair Consent Surface — Black-Hat Findings (branch spec/standing-pair-not-a-saga-v2 @ c8d6c1915)

Classification (single-context async, NOT saga) is SETTLED — attack the security claims only.

## Confirmed-OPEN findings

### BLACK-SP-001 (HIGH): discovery_context arm strictly weaker than shared_context arm
- §05-contexts.md line 1845: discovery_context qualifier = "not self-created **by the initiator**"
- §05-contexts.md line 1844: shared_context qualifier = "not self-created **by either party**"
- ASYMMETRY: discovery_context only excludes A, not B, not a colluding confederate C.
- Attack: B runs AutoAcceptPolicy{from: discovery_context}. Broker C (trusted by B) creates discovery context D, registers stranger A. A not self-created-by-A ⇒ gate passes ⇒ B silent auto-joins full-history bilateral-persistent pair. Reopens the exact outcome the shared_context "either party" fix closed.
- Fix: make discovery_context arm symmetric (bind independence from both parties + initiator-controlled confederates) OR document it provides weaker clearance, SHOULD NOT use for bilateral-persistent.

### BLACK-SP-002 (MEDIUM): shared_context "either party" doesn't reach a colluding confederate
- "not self-created by either party" closes SELF-manufacture, not CONFEDERATE-manufacture.
- Confederate C creates group G, adds both A and B; neither A nor B created G ⇒ gate passes.
- §9.3 threat model is "attacker can't manufacture HIS OWN records" — silent on confederate.
- Fix: document residual explicitly (mirror the honest fresh-DID-fleet disclosure).

### BLACK-SP-004 (HIGH, = SP-001 chain): fresh-DID-fleet reframe honest only on STRANGER path
- Line 1861 reframe ("approval-prompt spam not silent-join flood") holds ONLY if every fleet DID is a stranger to B.
- A fleet laundered onto a configured auto-accept arm (via SP-001) becomes SILENT joins, not prompts.
- Honesty of reframe is contingent on SP-001 being fixed. Spec presents arms + reframe as independent; they compose.

### BLACK-SP-005 (MEDIUM): collision-destroy replay-drivable by genuine did_lo Welcome
- Destroy (line 1832) gated on "self-created group + creator resolves to did_lo". Bound check is SOUND vs forged-creator-string + confused-deputy (actor-mutex + generation check are correct).
- GAP: no Welcome FRESHNESS binding. After did_hi reaped+re-drives a fresh self-created group, a REPLAYED genuine did_lo Welcome (creator legitimately = did_lo) passes the bound check ⇒ destroys did_hi's fresh legit group.
- Contrast §5.14.13 broadcast saga which stages grant_nonce/grant_timestamp_ms for replay defense.
- Fix: require destroy-triggering Welcome fresh relative to did_hi's current lifecycle generation/epoch.

### BLACK-SP-006 (LOW): non-member AlreadyExists constant-time asserted w/o mechanism
- Line 1871 "MUST be constant-time w.r.t. existence" but no mechanism (no dummy work / latency floor). Cache/index/view warmth branches timing. Cite mechanism or downgrade to SHOULD + acknowledged residual.

### BLACK-SP-003 (MEDIUM, disclosure-only): known_did is the highest-trust lowest-friction arm
- Correctly "by design" but it's the ONE arm granting fully-silent full-history join; social-eng / key-compromise target. Deserves same honest-disclosure paragraph the fleet got.

## What GENUINELY resists (do NOT weaken)
- Default-deny for true strangers (non-overridable for standing-pair Welcomes).
- shared_context "either party" qualifier closes SELF-manufacture exactly.
- Forged-creator-STRING destroy DoS foreclosed (ScpCredential.did==did_lo AND sig-key-resolves-to-did_lo-VM, §9.7.1).
- Confused-deputy in destroy: actor-mutex-across-{confirm+destroy+join} + generation/identity check = correct SCP concurrency discipline.
- Async consent-on-receipt closes synchronous block/pair-existence reply oracle; honestly NOT claiming offline-indistinguishability (published-KeyPackage bit disclosed).
- AlreadyExists existence-oracle clause: value+timing indistinguishable for non-members; found-vs-create ~0ms/~200ms hint correctly scoped to verified members only.

## Core insight
The two prior-pass fixes (shared_context per-arm qualifier + Sybil reframe) are REAL fixes for their exact vectors. What they MISSED: discovery_context arm hardened against a WEAKER adversary (initiator-only) than shared_context (either-party); neither arm reaches a colluding confederate. Silent-auto-join reopened through the sibling arm.
