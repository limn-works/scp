---
name: crypto22-s4-verifier-resolution-seam
description: CRYPTO-22 S4 (§9.7.1 checks 1-2) two-layer KeyPackage-attestation resolution seam — premises hold for S4, but two safety guarantees are transferred to S6/S7 and guarded only by prose, not mechanically.
metadata:
  type: project
---

CRYPTO-22 S4 (commit 3872f57da, branch crypto22-s4-code; story origin/crypto22-s4-prd-story:.docs/prds/keypackage-attestation.json). Verifier checks 1-2 (current-key + freshness), the two S2 deliberately deferred to the runtime caller. Related: [[adr057-crypto22-signer-seam]] (that was the SIGNER seam; this is the VERIFIER).

**Shape:** Layer A `verify_attestation_with_resolution` (pure, wasm-safe, scp-mls, re-exported) enforces check 2 (freshness ≤300s) then check 1 (current-VM via `ScpCredential::resolve_signing_key`) then delegates UNCHANGED to S2 `verify_attestation` (checks 3-13). Layer B `verify_add_or_update_attestation` (async, scp-runtime) resolves signer DID via injected DidResolver, fail-closed on Err/None, stamps resolved_at from injected Clock, delegates to A. Both layers have ZERO production callers (tests only) — S6/S7 wire.

**Verdict: premises hold for S4.** Public Layer A surface justified by ADR-057 browser reuse (same decision as S2's public verify_attestation). Honors S2's documented caller contract exactly. check-1 reuse of resolve_signing_key is sound: fragment-based (`verification_method_by_fragment`), so rotated→absent/#retired = CurrentKeyNotFound, rotated-but-fragment-holds-new-key = check-3 SignatureInvalid — §9.12 rotation-is-revocation intact.

**Two risks TRANSFERRED to downstream slices, guarded only by PRD prose (violates "enforce mechanically"):**
1. **Vacuous check-2 until 005.** Layer B stamps resolved_at = clock-now for EVERY resolve incl. ≤24h privacy-cache hits (ResolvedDidDocument exposes no age — open-question-a, needs #2211 resolver). So check-2's 300s gate always passes in prod; a cache-served pre-rotation doc can pass check 1, weakening rotation-revocation on Add. Story's downstreamSequencingConstraint gates S6-Add-wiring on 005 — but only in prose. No `#cfg`/type-state/pipeline-assert interlock.
2. **Update fails closed (grace deferred S7).** Fn is named `verify_add_or_update_attestation` and ACCEPTS AttestationTrigger::Update, but on Update+resolution-failure it fails closed instead of §9.7.1 last-known-good grace (= BLACK-C22-10 censorship/epoch-fork vector). Safe-but-incomplete while unwired. Asymmetry: downstreamSequencingConstraint gates the ADD path on 005 but is SILENT on gating Update-path wiring on the grace (S7). The "add_or_update" name invites a future wirer to wire both triggers and ship censorship-prone fail-closed Update.

Both are S6/S7 hazards, NOT S4 defects. Recommend S6/S7 carry a mechanical gate (pipeline assertion / type-state), not rely on the JSON prose.
