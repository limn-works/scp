---
name: standing-pair-not-saga-spec-review
description: Completeness review of spec/standing-pair-not-a-saga-v2 (HEAD 536c6d192) — reclassified standing-pair creation from cross-context saga to single-context async; verdict COMPLETE
metadata:
  type: project
---

Reviewed branch `spec/standing-pair-not-a-saga-v2` (HEAD 536c6d192), SPEC-ONLY by design (downstream Rust code deferred per artifact-flow invariant). Verdict: COMPLETE, nothing actionable.

**What it does:** standing-pair reclassified saga→single-context-async (genuine sagas now exactly two: §6.2.4 cross-context tool invoke + §5.14.13 broadcast hosting); §5.15.8 derivation adopts §9.5.1 length-prefix (len32 4-byte BE), retiring colon-freedom injectivity dependence; §3.8.1 new "canonical DID string form" section (RFC 3986 §6.2.2 + RFC 5895/IDNA2008 for did:web); Welcome-receipt mismatch guard (step-4 a0); §5.12.2 first-contact not-self-clearable disposition for ALL THREE TrustRequirement arms.

**Why it's complete (verified end-to-end):**
- Reclassification consistent across ALL layers: ADR-049 §3/§3a, DEFERRED doc (Status+Gap-1 banner+exit-criteria), §5.15.4, §5.15.8, §9.4.3, sdk-common, sketch. 10 sites use "two/both sagas"; ZERO residual "three sagas" claims (only false-positives: section numbers 9.4.3, code enum name StandingCommand::InitiateStandingPairCreate).
- §5.12.2↔§5.15.8 loop closed BIDIRECTIONALLY: §5.15.8 step-4(b) cross-refs §5.12.2 for all 3 arms; §5.12.2 line 755 explicitly cites "§5.15.8 step-4(b) cross-references this clause for all three arms." TrustRequirement (05-contexts §5.12.2 line 743-747) confirmed to have exactly 3 arms (shared_context, known_did, discovery_context); all 3 covered.
- Every cross-ref resolves and says what spec claims: §3.8.1 (03-identity:753), §9.5.1 4-byte-BE rule (09:line 10), ADR-049 §9/§10/Follow-ups#1 spawn-from-Welcome, §5.14.13 canonical-DID-as-key precedent, SCP-SAGA band 13000-13999 registered in sdk-common:45 + check-error-codes.sh:71.
- Deferral HONEST: code symbols named for downstream deletion/update all genuinely exist now — SagaInput::StandingPairCreate (actor_saga_*.rs), CreationReceipt (context/builder.rs:594), derive_standing_context_digest with literal b"standing:" colon-join (standing_helpers.rs:62-66), 3 reply_saga_deferred placeholders (handlers/{standing,tools,broadcast}.rs). Spec's "currently colon-joins, updated downstream" claim is accurate.

This spec leads code (no live divergence — standing-pair path not yet wired). Downstream impl PR owes: length-prefix helper rewrite, async creation path replacing reply_saga_deferred, orphan-type deletion. All honestly disclosed.
