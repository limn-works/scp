---
name: standing-pair-5158-round6-confirm
description: Confirming-pass result on §5.15.8 standing-pair "not a saga" reframe round-6 precision edits (destroy/live-join ordering, consent symmetry, no new vectors)
metadata:
  type: project
---

# §5.15.8 Standing-Pair round-6 confirming pass (branch spec/standing-pair-not-a-saga-v2 @ 4dab1f296)

CLEAN. All claims hold. No undisclosed bypass. Result: confirm.

**Why:** Confirming pass after consent/replay/send-gating hardening converged. Verified the three round-6 targets.

**How to apply:** If asked to re-review §5.15.8, these are settled — don't re-litigate; attack only NEW edits.

## Target 1: destroy/live-join ordering (the security-critical edit) — HOLDS
- Old bundle `{confirm-creator + destroy + join}`; new `{confirm-creator + fresh-join(consumes init key, fails on replay) + destroy}`, destroy strictly AFTER join succeeds.
- This CLOSES a real stale-destroy window the old ordering had: a replayed genuine did_lo Welcome could pass creator-credential check, fire destroy, THEN fail join on init-key-already-consumed → did_hi loses its group and does not rejoin. New ordering: replay fails join → destroys nothing.
- GROUNDED IN CODE: production_backend.rs::join_from_welcome (lines 563-569) consults consumed-init-key set FIRST, returns Err(KeyPackageReplay) BEFORE building any group state. Replay touches nothing.
- The destroy-before-insert at provider.rs:2514 (contexts.remove+destroy_group) is in the LEGACY MlsCryptoProvider::join_from_welcome which is #[cfg(any(test, feature="testing"))]-gated (provider.rs:~2471) and production-unreachable per ADR-049 §9. Not a production concern.
- Two-groups-under-one-id transient is benign: production join builds group in backend then actor installs; replay returns before group construction.

## Target 2: §5.12.5 example annotation — HONEST
- channel.send annotation: initiator sends immediately, Welcome-joined replica can DECRYPT not SEND until Phase-2E. Matches Known-limitation text exactly. No over/under-promise.

## Target 3: paragraph collapse + §9.7.1 label — NO new vector
- Collapsed destroy-and-rejoin paragraph carried no normative MUST (destroy MUST stays in bullet at line 1838; send-gating in Send-capability caveat line 1834). Lossless.
- §9.7.1 label fixed to "(MLS-to-SCP Concept Mapping)" — verified heading exists in 09-security-model.md line 571.

## Consent self-manufacture symmetry — CLOSED across all 3 arms
- shared_context: not-self-created by EITHER party + distinct. Residual: 3rd-party confederate (inherent, disclosed).
- discovery_context: made SYMMETRIC (not-self-created by EITHER party). Residual: malicious curator (inherent, disclosed).
- known_did: no manufacture surface. Residual: B's allowlist hygiene (inherent, disclosed).
- §9.3 cross-ref VERIFIED: 09-security-model.md line 227 has exact "(not self-created)" qualifier.
- All residuals are disclosed-inherent (trust-requirement semantics), NOT false closures.
