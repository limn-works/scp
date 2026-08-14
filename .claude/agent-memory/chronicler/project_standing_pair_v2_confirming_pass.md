---
name: project-standing-pair-v2-confirming-pass
description: standing-pair-not-a-saga-v2 (post round-4/5/6 polish, tip a0e02ab3b) — chronicler provenance pass; all anchors resolve, reaper-TTL & separator concerns resolved favorably
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2`, reviewed tip **a0e02ab3b** (merge-base f37372b25). Confirming provenance pass 2026-06-24. This rev is post the v1 I reviewed + 6 polish commits (rounds 4-6: consent-gate-first, block-list time-precision, reaper TTL, KP-residual). Verdict: **CLEAN, nothing actionable.**

**Why:** Reclassifies §5.15.8 standing-pair creation saga→single-context async; asserts exactly 2 live sagas (§6.2.4 tool-invoke, §5.14.13 broadcast). 5 files: 05-contexts.md (§5.12.2, §5.15.4, §5.15.8 rewrite), ADR-049 (§3/§3a + correction blockquote), DEFERRED-commit-11 (historical-correction markers), 09-security-model.md (§9.4.1 saga list 3→2), sdk-common.md (reserved-row de-specialize).

**How to apply (anchors VERIFIED in reviewed tree via `git show a0e02ab3b:<file>`):**
- §9.18.2 Domain Separators registry (09-security-model.md:1632) REGISTERS `"standing:"`/`"standing-"` → §5.15.8, classified non-§9.5.1 id-construction prefix. NO separator drift. (Resolves prior separator-registry concern.)
- Reaper `welcome_ttl` provenance RESOLVED FAVORABLY (was prior LOW): §5.12.3 line 787 "Invitation bundling" + InvitationBundle wire format `welcome_message: Vec<u8>` (line 798) show the bilateral MLS Welcome travels INSIDE an InvitationBundle, which §5.12.3.3 step-3 gives the 7-day relay TTL. So the standing-pair Welcome is NOT a bare Welcome — TTL inheritance is grounded, not asserted.
- §9.3 "(not self-created)" qualifier exists verbatim (09:227 "participation records from distinct contexts (not self-created)"). Step-4(b) + §5.12.2 edit reliance is accurate.
- §3.7.1 `is_globally_blocked` (03:545), §9.7.1 MLS-to-SCP (09:571), §5.12.5 found-vs-create (~0ms/~200ms, 05:953/999), §5.12.1/§5.12.6, §6.2.4/§5.14.13, §17 all resolve.
- ADR-049 §10 heading is literally "Actor panic recovery" — body (line 212) DOES contain standing-context auto-revive residual (BLACK-002), so §10 "auto-revive" cross-ref resolves to live content (NOT a finding). §Follow-ups (392) documents spawn-from-Welcome entrypoint #1.
- ZERO bare standing-pair-saga assertions survive as live claims. The two grep hits are benign: 05:1880 "has no saga export" (a negation) + DEFERRED:76 `InitiateStandingPairCreate` inside the explicitly-Superseded Gap-1 historical block.
- DEFERRED Status framing coherent: "Three of four originally specced" + "Correction (2026-06-18): only two live remain" reads as accurate historical record, not silent rewrite. sdk-common reserved row 13200-13999 de-specialized "standing-pair handshake"→"Future cross-context saga families" (correct — standing-pair no longer needs reserved saga band).

**GOTCHA (unchanged from v1):** working tree sits on `chore/fuzz-pin-nightly`; plain `grep .docs/` reads the OLD pre-correction text. MUST `git show a0e02ab3b:<file> | grep`. prds/main.json `CreationReceipt` is a DIFFERENT struct (general create_context rollback), out of scope.
