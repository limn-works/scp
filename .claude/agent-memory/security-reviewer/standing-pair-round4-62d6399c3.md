---
name: standing-pair-round4-62d6399c3
description: Security review of §5.15.8 standing-pair round-4 (commit 62d6399c3) — consent-arm guards+residual restructure, Welcome-freshness replay binding, generalized Welcome-joiner send-gating, existence-oracle constant-time. Verdict SOUND.
metadata:
  type: project
---

# §5.15.8 Standing-Pair Round-4 (62d6399c3) — Security Review

Branch `spec/standing-pair-not-a-saga-v2`. DOCS-ONLY. Round-4 commit closes round-3 review findings. Diff base 38b99639a. Continues [[standing-pair-single-context-async-37cf92e51]] (rounds 1-3).

## Verdict: SOUND, no blocking findings. 2 non-blocking Observations.

### Focus 1 — consent-arm guards+residual restructure (lines 33-36): SOUND
- Restructured into per-`TrustRequirement` arm (shared_context / discovery_context / known_did), each stating *Guards* + *Inherent residual*. Correctly rejects "one not-self-created predicate for all 3 arms."
- `shared_context`: guard = not-self-created-by-EITHER-party + distinct. Residual = colluding third-party confederate (by-design semantics of "trust a DID I share a non-self-created ctx with"). HONEST — this is the requirement's meaning, not a closable hole.
- `discovery_context`: guard now made SYMMETRIC (not-self-created by EITHER party). This DOES close the self-clear bypass: previously only "not self-created by initiator" → B could spin up its own discovery ctx, register initiator, self-clear; or initiator spins up its own. Symmetric guard closes both directions. Residual = delegated curator trust (malicious/compromised curator vouches for stranger). HONEST by-design — no "curator must be non-malicious" mechanism exists; B must point only at trusted curators.
- `known_did`: no manufacture surface (direct human allowlist). Residual = B's own allowlist hygiene. HONEST.
- All 3 residuals are genuine by-design semantics requiring B's prior trust config, NOT undisclosed holes. Self-clearing bypass closed across all arms.

### Focus 2 — Welcome-freshness replay binding on collision-destroy (line 21): SAFE
- New vector beyond creator-credential check: captured-and-replayed GENUINE did_lo Welcome → forced stale destroy of did_hi's current legit group.
- Fix: destroy gated on LIVE join — Welcome's KeyPackage init key still UNCONSUMED at fused-join two-anchor single-use point (ADR-049 §9). Replayed Welcome whose init key already consumed FAILS the join → MUST NOT trigger destroy. Destroy rides the SAME single-use init-key consumption that gates the join. VERIFIED against ADR-049 §9 line 163 (crypto-layer consumed-init-key set inside MlsBackend::join_from_welcome, RFC 9420 §10, fail-closed deny-by-default). Sound.

### Focus 3 — generalized Welcome-joiner send-gating + attacker-influenceable note (lines 17, 55): SOUND
- Send-gating now correctly GENERALIZED: ALL Welcome-joiners (common-case non-initiating peer AND collision-losing did_hi) can DECRYPT but not SEND until Phase-2E spawn-from-Welcome. Matches ADR-049 Follow-up #1 line 396 (populated E2eCryptoProvider, no actor-backed send handle). Not framed as edge case — it's the common path. Honest.
- Attacker-influenceable collision note: did_lo-relative attacker can deterministically race create under pair's derived_context_id to push victim (did_hi) onto send-gated path. Correctly bounded: attacker must ALREADY be consent-passed pair member (cleared step 4(b) stranger gate); worst case = receive-but-not-send in that ONE pair until Phase-2E; no cross-pair effect, no key exposure. Labeled security-relevant not mere feature gap. Sound.

### Focus 4 — existence-oracle constant-time + consent ordering (line 61): SOUND
- Constant-time-wrt-existence now has IMPLEMENTER MECHANISM: resolve membership first then constant-time decision, OR fixed-cost path doing equivalent work whether or not ctx exists; branch ONLY on membership never existence. Closes round-1 standing observation (requirement-without-how). value+TIMING indistinguishability both covered. §5.12.5 found-vs-create latency hint scoped to verified-member success path only. Sound.
- Consent-gate ordering (step 4): block list (3.7.1 is_globally_blocked) → opt-in policy (default-deny stranger) → join. Applied by JOINING peer on Welcome receipt BEFORE MLS processing. Block-first preserved. Sound.

## Observations carried forward (non-blocking)
- Injectivity STILL rides solely on human method-admission gate; len32-framing (§9.5.1) remains RECOMMENDED follow-up, deliberately deferred (derived_context_id derivation change = coordinated spec+code). MLS-layer defense-in-depth (GroupId/key-schedule/credentials) bounds blast radius. Track follow-up.
- All referenced sections verified at 62d6399c3: §5.12.2, §9.3 (line 227 "(not self-created)"), §3.7.1, ADR-049 §9/§10/Follow-up#1.
