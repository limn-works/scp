---
name: adr058-typed-trust-input-e6aa96a9a
description: ADR-058 typed SDK trust-input surface (verifyParticipationRequirements + checkCapabilityRequirements) across Py/TS/Swift/Kotlin, resolving #1991. APPROVED w/ observations.
metadata:
  type: project
---

ADR-058 review @e6aa96a9a (branch fu-1991, 5 commits: ADR + Py/TS/Swift/Kotlin). Input-side analog of ADR-057. **APPROVED** — built surface is sound.

**Why:** #1991 asked for a canonical typed SDK trust-input convention to kill the adjacent-JSON-string swap footgun in TS/Swift/Kotlin (Python already typed for participation). ADR-058 decision = typed objects in, serde JSON emitted internally, FFI stays JSON (no Rust/bridge change).

**How to apply / what's verified (don't re-flag):**
- Cross-SDK shape identity CONFIRMED for both ops. `checkCapabilityRequirements(contextId, subjectDid, requirements, agentCapabilities, challengeVerifications)` and `verifyParticipationRequirements(expectedSubject, requirements, profiles)` — identical arg names/order ×4. Placement per-SDK idiom (Python/Swift free-fn, TS/Kotlin SCP method) matches established convention.
- Encoders spot-checked against Rust serde (`scp-protocol/src/trust/{admission,challenge,participation}.rs`) and ALL CORRECT: VerificationLevel bare-string; ParticipationFact bare PascalCase; ParticipationThreshold + VerificationMethod externally-tagged (`{"AtLeast":n}`, `{"ChallengeVerified":{"challenge_type":<uri>}}`); challenge_type = bare URI string (Rust ChallengeType has custom Serialize → URI string, NOT `{"Uri":...}`); byte arrays → number arrays; score/context_id explicit-null (Swift custom encode(); Kotlin `encodeDefaults=true`; TS `?? null`; Python dict). Note serde tolerates Option absence, so explicit-null is cosmetic-parity not correctness.
- Footgun ELIMINATED: 3 adjacent typed arrays now compile-distinct in TS/Swift/Kotlin.

**Findings (all non-blocking):**
- MODERATE (alignment): #1991 AC-3 ("NO trust SDK op requires hand-serialized JSON") NOT fully met — `aggregate_trust_input` still stringly (Python `list[dict]`; TS 4 adjacent `...Json` strings @ scp.ts:2716, a WORSE footgun). ADR-058 scope-note defers it ("as touched"). If PR closes #1991, premature — the systemic op the issue named is untouched.
- LOW (Kotlin provenance): TrustAdmission.kt:15 cites "ADR-058 (.docs/adrs/phase-2.md)" — WRONG, pointer is in phase-4.md (grep phase-2=0, phase-4=2). Broken provenance. Only Kotlin errs.
- LOW (Python authorability): VerificationLevel/ChallengeVerificationMethod are single-field `name:str` dataclasses validated vs frozenset, not `str`-Enum/Literal. LLM porting TS `"SelfAttested"` → Python writes bare str → error. Internally consistent w/ pre-existing ParticipationFact/ParticipationThreshold Python precedent + ADR sanctions per-idiom, so not introduced here; whole Python family would benefit from enum.Enum.
- LOW (misuse-resistance asymmetry): Python does explicit 32/32/64 byte-length + range checks at construction; TS `readonly number[]` / Swift `[UInt8]` / Kotlin `List<UByte>` have NO length guard → wrong-length sig fails at bridge deserialize, not SDK boundary.
- INFO: Swift/Kotlin retain generated stringly `...Json` free fns (uniffi.scp.* / top-level) beside typed surface — unavoidable UniFFI artifact, typed is additive+doc'd-preferred, matches ADR-057 precedent.
