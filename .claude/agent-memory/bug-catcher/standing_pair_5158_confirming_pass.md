---
name: standing-pair-5158-confirming-pass
description: §5.15.8 standing-pair-not-a-saga round-5 precision review (4dab1f296) — CLEAN confirming pass; destroy/live-join TOCTOU foreclosed
metadata:
  type: project
---

# §5.15.8 Standing-Pair round-5 precision review (commit 4dab1f296) — CLEAN

Branch spec/standing-pair-not-a-saga-v2, docs-only. Diff touched 4 spots:
1. **Destroy/live-join ordering (TOCTOU foreclosed).** Prior bundle was `{confirm-creator + destroy + join}` (destroy BEFORE join = TOCTOU: replayed Welcome whose init key already consumed could still destroy). New text: "destroy MUST be sequenced strictly AFTER fused-join init-key consumption succeeds" + enumerated (a) confirm-creator → (b) fused-join (consumes init key, FAILS on replay) → (c) ONLY on success destroy. Bundle reworded `{confirm-creator + fresh-join (consumes init key, fails on replay) + destroy}` + guard "MUST NOT evaluate destroy against unconsumed/merely-asserted Welcome." Consistent w/ following Welcome-freshness paragraph. UNAMBIGUOUS.
2. **§5.12.5 worked-example annotation.** channel.send now notes initiator sends immediately, Welcome-joined peer DECRYPTs but can't SEND until Phase-2E. Matches §5.15.8 Send-capability caveat + Ok-contract + ADR-049 §Follow-ups #1. Consistent.
3. **Collapsed destroy-and-rejoin paragraph.** No normative MUST dropped (destroy MUST lives in bullets); redundant w/ Send-capability caveat line. Clean.
4. **§9.7.1 cross-ref label fix.** "MLS-to-SCP Concept Mapping" — heading VERIFIED to exist at 09-security-model.md:571; §9.7.1 line 17 carries the KeyPackage-sig/DID-VM binding rule §5.15.8 relies on.

Cross-checks: ADR-049 §9 two-anchor + fused-join (crypto-layer consumed-init-key set rejects replay inside join_from_welcome, fail-closed) FULLY backs the freshness claim. §5.15.4 saga FSM correctly excludes standing-pair. No residual contradiction. VERDICT: clean, no findings.
