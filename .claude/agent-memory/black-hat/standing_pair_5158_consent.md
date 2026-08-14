---
name: standing-pair-5158-consent
description: Threat model for §5.15.8 standing-pair consent gate (stranger bar, 3 TrustRequirement arms, collision-destroy, AlreadyExists oracle)
metadata:
  type: project
---

§5.15.8 standing-pair creation = single-context async (NOT a saga, settled). Branch spec/standing-pair-not-a-saga-v2 @ 62d6399c3 (commit-labeled round-4; prompt calls it round-5).

**Stranger-bar self-clear close (per-arm):**
- `shared_context`: qualifying ctx must be not-self-created-by-EITHER-party + distinct. Disclosed residual: colluding 3rd-party confederate who controls the ctx and adds B (inherent delegated-trust semantics, NOT closed).
- `discovery_context`: SYMMETRIC guard added round-4 — discovery ctx not-self-created-by-EITHER-party (was "not by initiator" only). Disclosed residual: malicious/compromised curator vouching (inherent, NOT closed). B must point only at trusted-curator discovery ctxs.
- `known_did`: bare allowlist, no qualifying-ctx predicate, no manufacture surface. Residual: B's own allowlist hygiene.
- §9.3 import is EXACT: line 227 of 09-security-model.md = "participation records from distinct contexts (not self-created)". Honest quote.

**Collision-destroy (did_hi destroys self-created group, joins did_lo's):**
- creator-credential check = cryptographically BOUND (ScpCredential.did==did_lo AND MLS sig key == did_lo DID-doc VM per §9.7.1). Forecloses forged-creator-string DoS.
- atomicity = per-context actor mutex across {confirm-creator+destroy+join} + generation/identity check (confused-deputy recreate close).
- Welcome-freshness binding (round-4 NEW): destroy triggered ONLY by LIVE join (init key unconsumed at fused-join two-anchor, ADR-049 §9). Replayed/stale did_lo Welcome fails the join → no destroy. Closes capture-replay stale-destroy.

**Send-gating (round-4 generalized):** ALL Welcome-joiners (common-case non-initiating peer AND collision-losing did_hi) can DECRYPT but cannot SEND until Phase-2E spawn-from-Welcome. Attacker-influenceable: did_lo can race-create to push victim onto send-gated path. Bounded: attacker must already be consent-passed pair member; worst case = receive-but-not-send in that one pair.

**AlreadyExists oracle:** non-member path constant-time-wrt-existence (value AND latency). Round-4 added implementer mechanism (membership-first / fixed-cost lookup). §5.12.5 found-vs-create latency hint applies to members only.

**Enforcement honesty:** stranger default-deny is SDK-consent-gate-layer MUST, NOT protocol-layer. Disclosed. Non-overridable by AutoAcceptPolicy (same intent as §5.12.2 tool/paid hard rules).

VERDICT (this review): self-manufacture closed symmetrically across all 3 arms; disclosed residuals (confederate, curator, allowlist hygiene, fresh-DID-fleet prompt-spam) are honest inherent delegated-trust semantics, not false closures. No undisclosed bypass found.
