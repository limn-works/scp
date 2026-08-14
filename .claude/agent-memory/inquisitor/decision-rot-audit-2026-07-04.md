---
name: decision-rot-audit-2026-07-04
description: Decision-rot audit of the ADR-058 trust-input / trust-error-parity cycle (PRs #2005/#2006/#2013/#2015/#2017/#2019). Two live scar-tissue defects + one ADR number collision.
metadata:
  type: project
---

Audit of completed cycle @origin/main 3b81f4107. Interrogated 6 artifact-level decisions for laundering-accident-into-intent / reverse-artifact-flow / premise-without-prior-understanding.

**Why:** these PRs relabeled a registry, doc-scoped a canonicalization scheme, ratified skew-const fragmentation, created ADR-058, and recategorized PyO3 exceptions — each a candidate for ratifying an accident.

**How to apply:** re-check these on any follow-up to the trust-input/error-code surfaces.

## SCAR-TISSUE (fix needed)

1. **VALID_7060-7066 Discovery-block squatting.** Block introduced b8b152602 (#1627) as a purpose-grouped **Discovery** reservation (7060 Discovery/7061 member/7062 context/7063 register/7064 unregister/7065 query/7066 probe). 7060/7061/7062 are STILL emitted live by production bridges: `crates/scp-ffi/src/discovery.rs:100/159/321` + `crates/scp-ffi/uniffi/src/bridge.rs:7900`. This cycle relabeled 7060-7065 doc-comments to Swift-SDK trust byte-length/encode purposes AND Swift `bindings/swift/Sources/SCP/Trust.swift` now emits 7060-7065 — creating a LIVE double-booking of 7060/7061/7062 (same code string, two subsystems, two documented meanings). Registry's own charter (error_codes.rs header) is "eliminates cross-bridge divergence, makes auditing trivial" — squatting breaks it. `check-error-codes.sh` only range-checks the band; VALID-band uniqueness is manual, so nothing caught it. FIX: Swift use fresh unused VALID codes (7000-7999 has room, e.g. 7100+); restore Discovery doc-comments 7060-7066.

2. **Attestation claim MessagePack contradicts §9.5.2.** `canonical_attestation_bytes` (scp-protocol/src/trust/attestation.rs:1181) serializes `claim` with `rmp_serde::to_vec_named` (MessagePack). §9.5.2 Attestation row field-5 mandates `claim` = **compact JSON** ("equivalent to json.dumps(separators)"). §9.5 line 489 EXPLICITLY rejects MessagePack for cross-impl canonical hashing ("no canonical form standard, field ordering varies by library"). evidence/revocation_status MessagePack IS §9.5.2-sanctioned; only `claim` diverges. PR #2005 jcs.rs + attestation.rs doc-comments documented MessagePack as "intentional / fixed by construction" WITHOUT an ADR and while contradicting §9.5.2 claim encoding — laundering a pre-existing spec-divergence into documented intent (reverse artifact flow). FIX via ADR: either code→compact-JSON claim per §9.5.2, or amend §9.5.2 with a cross-impl-determinism justification for MessagePack (the real unevaluated question: is rmp_serde::to_vec_named of a serde_json::Value deterministic across Python/JS/Swift/Kotlin msgpack libs?). Not a doc-comment.

## INCONCLUSIVE (human)

3. **ADR-057 NUMBER COLLISION.** Two distinct Accepted ADR-057s: `.docs/adrs/phase-2.md:1959` "Structured Capability/Trust Validation Across the FFI" (the structured-trust-OUTPUTS decision) AND standalone `.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md`. ADR-058 (new this cycle) cites "ADR-057 (structured trust outputs)" as its input-side analog — referent is REAL (phase-2 one) so the analogy is correctly grounded, but the NUMBER is ambiguous. Renumbering an Accepted ADR is a human call.

## SOUND

- ADR-058 typed SDK trust-input surface: consistent with ADR-048 §1 (FFI stays JSON) + §7 (per-SDK idiom); fixes the JSON-input asymmetry I flagged in [[adr057_c3c_trust_ffi_shape]]; extends the already-accepted ConsequenceRule/CachedAttestation typed-input convention. Residual (accepted, not regression): 4-language hand-rolled models pinned only by fixture round-trip tests, no type-level drift prevention — inherent to the ADR-048 §1 JSON boundary.
- §7.3.4.4 verification-flow paragraph (#2006): faithful to `verify_challenge_verification` (context binding rejects None + mismatch, challenge.rs:908; subject binding :895); symmetric with established §7.3.2.1 participation sibling + §7.3 line 827. context_id IS in signed canonical bytes.
- §9.14 skew "independent knobs" (#2013): spec's own §9.5 param tables (lines 1716/1737/1824) list distinct per-subsystem tolerances sharing the 5-min default — "independent knobs" is spec-faithful, false-coupling argument legitimate. Residual: no test pins all four to §9.14's value; doc discourages the unification that would prevent drift. Relates to [[participation-freshness-skew-c35c62703]].
- PyO3 exception recategorization (#2017): correction TOWARD canonical taxonomy — sdk-common.md maps SCP-VALID- band → ValidationError by definition; PyRuntimeError was the uncoded/miscoded accident. Aligns to UniFFI reference + NAPI. Not a regression.
