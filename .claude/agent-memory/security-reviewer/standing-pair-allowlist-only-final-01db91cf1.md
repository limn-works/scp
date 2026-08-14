# Standing-Pair "Not a Saga" v2 — allowlist-only FINAL (01db91cf1) — 2026-06-24 — ZERO FINDINGS

Branch spec/standing-pair-not-a-saga-v2, HEAD 01db91cf1, base f37372b25. Docs-only.
Successor to 43cc189f0 (allowlist-only). One new commit 01db91cf1 on top.
8 files: 05-contexts, 09-security-model, 03-identity, technical-overview, sketch, sdk-common, ADR-049, DEFERRED.

## PRIOR LOW (43cc189f0) NOW RESOLVED
- 43cc189f0 provenance note named ONLY scp-protocol as carrying Any/SharedContext; WASM check_trust was 2nd undisclosed copy.
- 01db91cf1 provenance note (05-contexts.md:746) now names **BOTH** removal sites: "scp-protocol context::policy enum (+ invitation.rs satisfies_trust) AND the separate WASM bridge check_trust reimplementation (scp-ffi/wasm, ADR-034)". COMPLETE.

## LIVE-CODE VERIFICATION (provenance note accurate)
- WASM context.rs:2565-2573 check_trust has Some("Any")=>true, Some("SharedContext"), Explicit arms — matches note. Called at :2716.
- scp-protocol policy.rs:22-29 enum: Any, SharedContext, Explicit(Vec<DID>) — NO DiscoveryContext variant (confirms note's "never implemented discovery_context arm").
- invitation.rs:331-335 satisfies_trust: Any=>true, SharedContext, Explicit — matches note.
- evaluate_invitation policy: Option<&AutoAcceptPolicy>; line 259 `if let Some(policy)` gates; absent => PromptAgent (line 254). Default-deny MATCHES live code.

## §5.13.7 CHILD-CONTEXT FIX (correct)
- Rewrote "Auto-accept policies" → "Auto-accept and child contexts": lineage = cryptographically-enforced FLOOR on who-can-reach-you (relay-enforced §5.13.2), NOT a trust signal, does NOT trigger auto-accept. Routes through same §5.12.2 known_did allowlist + default-deny.
- GROUNDED: §5.13.2 L1088 "relay-level validation... protocol-level guarantee, not an SDK honor system." Floor claim accurate. Removed the prior "parent lineage provides a stronger trust signal" weak-signal language.

## SWEEP (final) — NO residual infer-trust-from-weak-signal sibling
- §5.12.2 surface clean (L738 from:TrustRequirement now only known_did).
- All shared_context/discovery_context greps in UNRELATED subsystems: §07:851 DataProvenance.discoveryMethod (attribution), §22 addressing DiscoveryContext layer, sketch.md:1485/1512/1553/1598 discovery-method provenance + DiscoveryResult.source, sketch.md:125/129 query filter. NONE is a TrustRequirement auto-accept arm.
- No alternate auto-accept entry point bypassing evaluate_invitation.

## OTHER VERIFIED
- memory_scope:full at 05-contexts.md:637 grounds §5.15.8 step-4(b) default-deny justification.
- join-then-destroy (L1846/1849): survivor did_lo ignores all; did_hi joins did_lo's THEN destroys own orphan (destroy after fused-join consumption — round-6 ordering intact).
- existence oracle (value+timing constant-time), block gate (consent-on-receipt, no sync reply oracle), KeyPackage no-drain (did_lo ignore-rule, single-use at join), length-prefix injectivity unconditional — ALL sound, unchanged.
- ADR-049/DEFERRED/sdk-common: 3-saga→2-saga reclassification consistent; SCP-SAGA 13000-13999 band registration claim accurate (sdk-common L60-63 table). No load-bearing guarantee dropped.

## VERDICT: airtight. Allowlist-only across §5.12.2 AND §5.13.7. No sibling remains. ZERO actionable findings.
